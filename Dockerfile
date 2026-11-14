FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY backend/Tester.Api.csproj backend/
RUN dotnet restore backend/Tester.Api.csproj
COPY backend/ backend/
RUN dotnet publish backend/Tester.Api.csproj -c Release -o /out --no-restore
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /out ./
COPY public/ ./wwwroot/
COPY sql/sqlite-schema.sql ./sql/sqlite-schema.sql
ENV ASPNETCORE_URLS=http://0.0.0.0:10000
ENV SQLITE_PATH=/app/Data/tester.db
EXPOSE 10000
ENTRYPOINT ["dotnet","Tester.Api.dll"]
