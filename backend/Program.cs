using System.Data;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Data.Sqlite;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

var builder=WebApplication.CreateBuilder(args);
var secret=Environment.GetEnvironmentVariable("JWT_SECRET");
if(string.IsNullOrEmpty(secret)||Encoding.UTF8.GetByteCount(secret)<32) throw new Exception("JWT_SECRET must contain at least 32 bytes");
var dbPath=Environment.GetEnvironmentVariable("SQLITE_PATH")??"Data/tester.db";
Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(dbPath))!);
var connString=new SqliteConnectionStringBuilder{DataSource=dbPath,Mode=SqliteOpenMode.ReadWriteCreate}.ToString();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o=>o.TokenValidationParameters=new TokenValidationParameters{ValidateIssuer=false,ValidateAudience=false,ValidateLifetime=true,ValidateIssuerSigningKey=true,IssuerSigningKey=new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),ClockSkew=TimeSpan.FromSeconds(20)});
builder.Services.AddAuthorization();
var app=builder.Build();
app.UseDefaultFiles();app.UseStaticFiles();app.UseAuthentication();app.UseAuthorization();
async Task<List<Dictionary<string,object?>>> Query(string sql,params object?[] args){
 await using var c=new SqliteConnection(connString);await c.OpenAsync();await using var cmd=c.CreateCommand();cmd.CommandText=sql;
 for(int i=0;i<args.Length;i++)cmd.Parameters.AddWithValue("@p"+i,args[i]??DBNull.Value);
 await using var reader=await cmd.ExecuteReaderAsync();var result=new List<Dictionary<string,object?>>();
 while(await reader.ReadAsync()){var row=new Dictionary<string,object?>();for(int i=0;i<reader.FieldCount;i++)row[reader.GetName(i)]=reader.IsDBNull(i)?null:reader.GetValue(i);result.Add(row);}return result;
}
static string S(JsonElement e,string key,string def="")=>e.ValueKind==JsonValueKind.Object&&e.TryGetProperty(key,out var x)&&x.ValueKind!=JsonValueKind.Null?x.ToString():def;
static long? L(JsonElement e,string key)=>long.TryParse(S(e,key),out var v)?v:null;
static bool Allowed(string? role,string minimum)=>minimum switch{"admin"=>role=="admin","manager"=>role is "admin" or "manager","operator"=>role is "admin" or "manager" or "operator","client"=>role=="client",_=>role is "admin" or "manager" or "operator" or "viewer"};
async Task<IResult> Guard(HttpContext ctx,string minimum,Func<Dictionary<string,object?>,Task<IResult>> handler){
 var id=ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);if(!long.TryParse(id,out var uid))return Results.Unauthorized();
 var users=await Query("SELECT id,username,role,active,client_id,token_version FROM users WHERE id=@p0",uid);var u=users.FirstOrDefault();
 if(u==null||Convert.ToInt64(u["active"])!=1||Convert.ToInt64(u["token_version"])!=long.Parse(ctx.User.FindFirstValue("ver")??"-1"))return Results.Unauthorized();
 if(!Allowed(u["role"]?.ToString(),minimum))return Results.Forbid();return await handler(u);
}
app.MapGet("/api/health",async()=>{await Query("SELECT 1");return Results.Ok(new{ok=true,platform="ASP.NET Core",database="SQLite"});});
app.MapPost("/api/login",async(JsonElement b)=>{var users=await Query("SELECT * FROM users WHERE username=@p0 AND active=1",S(b,"username"));var u=users.FirstOrDefault();if(u==null||!BCrypt.Net.BCrypt.Verify(S(b,"password"),u["password_hash"]?.ToString()))return Results.Unauthorized();var claims=new[]{new Claim(ClaimTypes.NameIdentifier,u["id"]!.ToString()!),new Claim(ClaimTypes.Role,u["role"]!.ToString()!),new Claim("ver",u["token_version"]!.ToString()!)};var token=new JwtSecurityToken(claims:claims,expires:DateTime.UtcNow.AddHours(8),signingCredentials:new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),SecurityAlgorithms.HmacSha256));return Results.Ok(new{token=new JwtSecurityTokenHandler().WriteToken(token),role=u["role"]});});
app.MapGet("/api/me",(HttpContext c)=>Guard(c,"viewer",u=>Task.FromResult<IResult>(Results.Ok(u))));
app.MapGet("/api/admin/users",(HttpContext c)=>Guard(c,"admin",async _=>Results.Ok(await Query("SELECT id,username,role,active,client_id,created_at FROM users ORDER BY id"))));
app.MapPost("/api/admin/users",(HttpContext c,JsonElement b)=>Guard(c,"admin",async _=>{var name=S(b,"username");var password=S(b,"password");var role=S(b,"role","viewer");var cid=L(b,"client_id");if(name.Length<1||password.Length<12||!new[]{"viewer","operator","manager","client"}.Contains(role)||(role=="client"&&cid==null))return Results.BadRequest(new{error="Invalid account"});if(role=="client"&&(await Query("SELECT id FROM clients WHERE id=@p0",cid)).Count==0)return Results.BadRequest(new{error="Unknown client"});if((await Query("SELECT id FROM users WHERE username=@p0",name)).Count>0)return Results.Conflict(new{error="اسم المستخدم موجود بالفعل. اختر اسمًا آخر."});try{await Query("INSERT INTO users(username,password_hash,role,client_id) VALUES(@p0,@p1,@p2,@p3)",name,BCrypt.Net.BCrypt.HashPassword(password),role,cid);}catch(Microsoft.Data.Sqlite.SqliteException ex) when(ex.SqliteErrorCode==19){return Results.Conflict(new{error="اسم المستخدم موجود بالفعل. اختر اسمًا آخر."});}return Results.StatusCode(201);}));
app.MapPatch("/api/admin/users/{id:long}",(HttpContext c,long id,JsonElement b)=>Guard(c,"admin",async u=>{if(id==Convert.ToInt64(u["id"])&&S(b,"active")=="false")return Results.BadRequest();if(!bool.TryParse(S(b,"active"),out var active))return Results.BadRequest();await Query("UPDATE users SET active=@p0,token_version=token_version+1 WHERE id=@p1",active?1:0,id);return Results.Ok();}));
var tables=new Dictionary<string,string[]>{["clients"]=["name","contact","email","phone"],["channels"]=["name","category","frequency"],["programs"]=["channel_id","name","air_time","description"],["campaigns"]=["client_id","name","start_date","end_date","budget","status"],["creatives"]=["campaign_id","name","duration_seconds","reference_url"],["spots"]=["campaign_id","channel_id","program_id","creative_id","planned_at","price"],["airings"]=["spot_id","actual_at","source","evidence_url","notes"]};
foreach(var item in tables){var table=item.Key;var columns=item.Value;
 app.MapGet("/api/"+table,(HttpContext c)=>Guard(c,"viewer",async _=>Results.Ok(await Query($"SELECT * FROM {table} ORDER BY id DESC LIMIT 1000"))));
 app.MapPost("/api/"+table,(HttpContext c,JsonElement b)=>Guard(c,"operator",async _=>{var keys=columns.Where(k=>b.TryGetProperty(k,out var ignoredProperty)).ToArray();if(keys.Length==0)return Results.BadRequest();var values=keys.Select(k=>(object?)(S(b,k)==""?null:S(b,k))).ToArray();await Query($"INSERT INTO {table} ({string.Join(',',keys)}) VALUES ({string.Join(',',keys.Select((_,i)=>"@p"+i))})",values);return Results.StatusCode(201);}));
 app.MapPut("/api/"+table+"/{id:long}",(HttpContext c,long id,JsonElement b)=>Guard(c,"manager",async _=>{var keys=columns.Where(k=>b.TryGetProperty(k,out var ignoredProperty)).ToArray();if(keys.Length==0)return Results.BadRequest();var values=keys.Select(k=>(object?)(S(b,k)==""?null:S(b,k))).Append(id).ToArray();await Query($"UPDATE {table} SET {string.Join(',',keys.Select((k,i)=>k+"=@p"+i))} WHERE id=@p{keys.Length}",values);return Results.Ok();}));
 app.MapDelete("/api/"+table+"/{id:long}",(HttpContext c,long id)=>Guard(c,"admin",async _=>{await Query($"DELETE FROM {table} WHERE id=@p0",id);return Results.NoContent();}));
}
app.MapPost("/api/admin/seed-samples",(HttpContext ctx)=>Guard(ctx,"admin",async _=>{
 var marker="DEMO | Cairo Retail Campaign";
 if((await Query("SELECT id FROM campaigns WHERE name=@p0",marker)).Count>0)
  return Results.Conflict(new{error="البيانات التجريبية موجودة بالفعل. لم يتم تكرارها."});
 await using var connection=new SqliteConnection(connString);
 await connection.OpenAsync();
 await using var transaction=await connection.BeginTransactionAsync();
 async Task<long> Insert(string sql,params object?[] values){
  await using var cmd=connection.CreateCommand();cmd.Transaction=(SqliteTransaction)transaction;cmd.CommandText=sql;
  for(var i=0;i<values.Length;i++)cmd.Parameters.AddWithValue("@p"+i,values[i]??DBNull.Value);
  await cmd.ExecuteNonQueryAsync();
  cmd.CommandText="SELECT last_insert_rowid()";cmd.Parameters.Clear();return Convert.ToInt64(await cmd.ExecuteScalarAsync());
 }
 try{
  var client=await Insert("INSERT INTO clients(name,contact,email,phone) VALUES(@p0,@p1,@p2,@p3)","DEMO | Nile Retail Egypt","Marketing Department","demo-retail@example.com","01000000000");
  var channel=await Insert("INSERT INTO channels(name,category,frequency) VALUES(@p0,@p1,@p2)","DEMO | Cairo TV","Satellite TV","Sample / no actual frequency");
  var program=await Insert("INSERT INTO programs(channel_id,name,air_time,description) VALUES(@p0,@p1,@p2,@p3)",channel,"DEMO | Evening Show","20:30","برنامج افتراضي لعرض سيناريو الاختبار");
  var campaign=await Insert("INSERT INTO campaigns(client_id,name,start_date,end_date,budget,status) VALUES(@p0,@p1,@p2,@p3,@p4,@p5)",client,marker,"2026-11-15","2026-12-15",250000,"demo");
  var creative=await Insert("INSERT INTO creatives(campaign_id,name,duration_seconds,reference_url) VALUES(@p0,@p1,@p2,@p3)",campaign,"DEMO | 30-second TV Spot",30,"https://example.com/");
  var spot=await Insert("INSERT INTO spots(campaign_id,channel_id,program_id,creative_id,planned_at,price) VALUES(@p0,@p1,@p2,@p3,@p4,@p5)",campaign,channel,program,creative,"2026-11-20 20:45:00",12500);
  await Insert("INSERT INTO airings(spot_id,actual_at,source,evidence_url,notes) VALUES(@p0,@p1,@p2,@p3,@p4)",spot,"2026-11-20 20:45:45","DEMO — simulated record",null,"سجل توضيحي افتراضي، ليس دليل بث حقيقي");
  await Insert("INSERT INTO test_runs(name,target_type,target_url,notes,status,client_id) VALUES(@p0,@p1,@p2,@p3,@p4,@p5)","DEMO | Example.com Website Test","website","https://example.com/","بيانات تجريبية، لم يُجر اختبار حقيقي بعد","pending",client);
  await transaction.CommitAsync();
  return Results.Ok(new{message="تم إنشاء بيانات واقعية الشكل لكنها افتراضية وموسومة DEMO",client_id=client,campaign_id=campaign});
 }catch(Microsoft.Data.Sqlite.SqliteException ex){
  await transaction.RollbackAsync();
  return Results.Json(new{error="تعذر إضافة البيانات. تحقق من العلاقات والقيود.",sqlite_code=ex.SqliteErrorCode},statusCode:409);
 }
}));
app.MapPost("/api/admin/seed-bulk",(HttpContext ctx)=>Guard(ctx,"admin",async _=>{
 var password=Environment.GetEnvironmentVariable("DEMO_USERS_PASSWORD");
 if(string.IsNullOrWhiteSpace(password)||password.Length<12)return Results.Json(new{error="اضبط DEMO_USERS_PASSWORD بطول 12 حرفًا على الأقل داخل Render قبل إنشاء حسابات التجربة"},statusCode:400);
 if((await Query("SELECT id FROM clients WHERE name=@p0","DEMO | Delta Electronics")).Count>0)return Results.Conflict(new{error="مجموعة DEMO موجودة بالفعل"});
 await using var db=new SqliteConnection(connString);await db.OpenAsync();await using var tx=await db.BeginTransactionAsync();
 async Task<long> Add(string sql,params object?[] args){await using var cmd=db.CreateCommand();cmd.Transaction=(SqliteTransaction)tx;cmd.CommandText=sql;for(int i=0;i<args.Length;i++)cmd.Parameters.AddWithValue("@p"+i,args[i]??DBNull.Value);await cmd.ExecuteNonQueryAsync();cmd.CommandText="SELECT last_insert_rowid()";cmd.Parameters.Clear();return Convert.ToInt64(await cmd.ExecuteScalarAsync());}
 try{
 var clients=new[]{("Delta Electronics","electronics"),("Nile Foods","foods"),("Cairo Travel","travel")};
 var channels=new[]{("Cairo News","News"),("Nile Entertainment","Entertainment"),("Sports Egypt","Sports")};
 var ids=new List<long>();var chids=new List<long>();
 foreach(var (name,segment) in clients)ids.Add(await Add("INSERT INTO clients(name,contact,email,phone) VALUES(@p0,@p1,@p2,@p3)","DEMO | "+name,"Demo "+segment,"demo-"+segment+"@example.com","01000000000"));
 foreach(var (name,category) in channels)chids.Add(await Add("INSERT INTO channels(name,category,frequency) VALUES(@p0,@p1,@p2)","DEMO | "+name,category,"Simulated"));
 for(int i=0;i<3;i++){
  var program=await Add("INSERT INTO programs(channel_id,name,air_time,description) VALUES(@p0,@p1,@p2,@p3)",chids[i],"DEMO | Evening Program "+(i+1),"20:00","Simulated schedule");
  for(int j=0;j<3;j++){
   var campaign=await Add("INSERT INTO campaigns(client_id,name,start_date,end_date,budget,status) VALUES(@p0,@p1,@p2,@p3,@p4,@p5)",ids[i],"DEMO | Campaign "+(i+1)+"-"+(j+1),"2026-11-15","2026-12-15",50000+(i*3+j)*15000,"demo");
   var creative=await Add("INSERT INTO creatives(campaign_id,name,duration_seconds,reference_url) VALUES(@p0,@p1,@p2,@p3)",campaign,"DEMO | Creative "+(j+1),15+15*j,"https://example.com/");
   var spot=await Add("INSERT INTO spots(campaign_id,channel_id,program_id,creative_id,planned_at,price) VALUES(@p0,@p1,@p2,@p3,@p4,@p5)",campaign,chids[i],program,creative,"2026-11-"+(20+j)+" 20:30:00",6000+1000*j);
   if(j!=2)await Add("INSERT INTO airings(spot_id,actual_at,source,notes) VALUES(@p0,@p1,@p2,@p3)",spot,"2026-11-"+(20+j)+" 20:31:00","DEMO simulated","Not real broadcast evidence");
  }
  await Add("INSERT INTO test_runs(name,target_type,target_url,notes,status,client_id) VALUES(@p0,@p1,@p2,@p3,'pending',@p4)","DEMO | Website check "+(i+1),"website","https://example.com/","Pending: no automated result yet",ids[i]);
 }
 var hash=BCrypt.Net.BCrypt.HashPassword(password);
 for(int i=0;i<3;i++)await Add("INSERT INTO users(username,password_hash,role,client_id) VALUES(@p0,@p1,'client',@p2)","demo_client_"+(i+1),hash,ids[i]);
 await Add("INSERT INTO users(username,password_hash,role) VALUES(@p0,@p1,@p2)","demo_operator",hash,"operator");
 await Add("INSERT INTO users(username,password_hash,role) VALUES(@p0,@p1,@p2)","demo_manager",hash,"manager");
 await tx.CommitAsync();
 return Results.Ok(new{message="Created labeled fictional demo dataset",clients=3,channels=3,programs=3,campaigns=9,creatives=9,spots=9,airings=6,test_runs=3,users=5});
 }catch(Exception){await tx.RollbackAsync();return Results.Json(new{error="تعذر إنشاء مجموعة DEMO؛ لم تُحفظ بيانات جزئية. تحقق من تكرار المستخدمين أو قيود قاعدة البيانات"},statusCode:409);}
}));
app.MapPost("/api/test-runs",(HttpContext c,JsonElement b)=>Guard(c,"operator",async u=>{var type=S(b,"target_type");if(!new[]{"website","api","windows_exe","android_apk","advertising_media","broadcast_monitor"}.Contains(type)||S(b,"name").Length==0)return Results.BadRequest();await Query("INSERT INTO test_runs(name,target_type,target_url,notes,created_by,status,client_id) VALUES(@p0,@p1,@p2,@p3,@p4,'pending',@p5)",S(b,"name"),type,S(b,"target_url"),S(b,"notes"),u["id"],L(b,"client_id"));return Results.StatusCode(201);}));
app.MapGet("/api/test-runs",(HttpContext c)=>Guard(c,"viewer",async _=>Results.Ok(await Query("SELECT t.*,u.username creator FROM test_runs t LEFT JOIN users u ON u.id=t.created_by ORDER BY t.id DESC LIMIT 500"))));
app.MapPost("/api/test-runs/{id:long}/results",(HttpContext c,long id,JsonElement b)=>Guard(c,"operator",async _=>{if(!new[]{"passed","failed","blocked"}.Contains(S(b,"result")))return Results.BadRequest();await Query("INSERT INTO test_results(run_id,test_name,result,details) VALUES(@p0,@p1,@p2,@p3)",id,S(b,"test_name"),S(b,"result"),S(b,"details"));return Results.StatusCode(201);}));
app.MapGet("/api/test-runs/{id:long}/report",(HttpContext c,long id)=>Guard(c,"viewer",async _=>{var runs=await Query("SELECT * FROM test_runs WHERE id=@p0",id);if(runs.Count==0)return Results.NotFound();var rows=await Query("SELECT * FROM test_results WHERE run_id=@p0",id);return Results.Ok(new{run=runs[0],results=rows,counts=new{passed=rows.Count(r=>r["result"]?.ToString()=="passed"),failed=rows.Count(r=>r["result"]?.ToString()=="failed"),blocked=rows.Count(r=>r["result"]?.ToString()=="blocked")},ai_generated=false});}));
app.MapGet("/api/client/profile",(HttpContext c)=>Guard(c,"client",async u=>Results.Ok((await Query("SELECT id,name,contact,email FROM clients WHERE id=@p0",u["client_id"])).FirstOrDefault())));
app.MapGet("/api/client/reports",(HttpContext c)=>Guard(c,"client",async u=>Results.Ok(await Query("SELECT id,name,target_type,status,created_at FROM test_runs WHERE client_id=@p0 ORDER BY id DESC",u["client_id"]))));
app.MapGet("/api/client/reports/{id:long}",(HttpContext c,long id)=>Guard(c,"client",async u=>{var runs=await Query("SELECT * FROM test_runs WHERE id=@p0 AND client_id=@p1",id,u["client_id"]);if(runs.Count==0)return Results.NotFound();return Results.Ok(new{run=runs[0],results=await Query("SELECT * FROM test_results WHERE run_id=@p0",id)});}));
app.MapGet("/api/summary",(HttpContext c)=>Guard(c,"viewer",async _=>Results.Ok((await Query("SELECT (SELECT COUNT(*) FROM campaigns) campaigns,(SELECT COUNT(*) FROM channels) channels,(SELECT COUNT(*) FROM spots) spots,(SELECT COUNT(*) FROM spots s WHERE s.planned_at < datetime('now') AND NOT EXISTS(SELECT 1 FROM airings a WHERE a.spot_id=s.id)) missing,(SELECT COALESCE(SUM(price),0) FROM spots) scheduled_cost"))[0])));
app.MapGet("/api/monitor",(Delegate)((HttpContext c)=>Guard(c,"viewer",async _=>Results.Ok(await Query("SELECT s.id,s.planned_at,s.price,c.name campaign,ch.name channel,cr.name creative,a.actual_at,a.evidence_url,CASE WHEN a.id IS NULL AND s.planned_at > datetime('now') THEN 'upcoming' WHEN a.id IS NULL THEN 'missing' WHEN ABS((julianday(a.actual_at)-julianday(s.planned_at))*86400)>120 THEN 'late' ELSE 'matched' END result FROM spots s JOIN campaigns c ON c.id=s.campaign_id LEFT JOIN channels ch ON ch.id=s.channel_id LEFT JOIN creatives cr ON cr.id=s.creative_id LEFT JOIN airings a ON a.id=(SELECT aa.id FROM airings aa WHERE aa.spot_id=s.id ORDER BY aa.id DESC LIMIT 1) ORDER BY s.planned_at DESC LIMIT 1000")))));
app.MapGet("/api/ai/monitor-insights",(Delegate)((HttpContext c)=>Guard(c,"viewer",async _=>{var r=(await Query("SELECT (SELECT COUNT(*) FROM spots s WHERE s.planned_at < datetime('now') AND NOT EXISTS(SELECT 1 FROM airings a WHERE a.spot_id=s.id)) missing,(SELECT COUNT(DISTINCT spot_id) FROM airings) recorded,(SELECT COUNT(*) FROM spots) total"))[0];return Results.Ok(new{source="rules-based analysis (not generative AI)",metrics=r,insights=new[]{"Missing records do not prove missed broadcasts"}});})));
app.MapFallbackToFile("index.html");
await using(var c=new SqliteConnection(connString)){await c.OpenAsync();await using(var cmd=c.CreateCommand()){cmd.CommandText=await File.ReadAllTextAsync(Path.Combine(app.Environment.ContentRootPath,"sql","sqlite-schema.sql"));await cmd.ExecuteNonQueryAsync();}}
var usersCount=await Query("SELECT COUNT(*) n FROM users");if(Convert.ToInt64(usersCount[0]["n"])==0){var admin=Environment.GetEnvironmentVariable("ADMIN_USER");var pw=Environment.GetEnvironmentVariable("ADMIN_PASSWORD");if(string.IsNullOrWhiteSpace(admin)||string.IsNullOrWhiteSpace(pw)||pw.Length<12)throw new Exception("ADMIN_USER and ADMIN_PASSWORD (12+ chars) required on first run");await Query("INSERT INTO users(username,password_hash,role) VALUES(@p0,@p1,'admin')",admin,BCrypt.Net.BCrypt.HashPassword(pw));}
app.Run();
