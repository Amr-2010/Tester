const {app,BrowserWindow,shell}=require('electron');
const path=require('path');
const fs=require('fs');
function create(){
 const win=new BrowserWindow({width:1280,height:850,minWidth:800,minHeight:600,webPreferences:{nodeIntegration:false,contextIsolation:true,sandbox:true}});
 const configFile=path.join(__dirname,'config.json');
 const config=JSON.parse(fs.readFileSync(configFile,'utf8'));
 if(!/^https:\/\/[^\s]+$/.test(config.appUrl)) throw new Error('Set HTTPS Render URL in desktop/config.json');
 win.loadURL(config.appUrl);
 win.webContents.setWindowOpenHandler(({url})=>{if(/^https:\/\//.test(url))shell.openExternal(url);return {action:'deny'}});
}
app.whenReady().then(create);
app.on('window-all-closed',()=>{if(process.platform!=='darwin')app.quit()});
