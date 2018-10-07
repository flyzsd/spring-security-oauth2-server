Reference:
https://www.devglan.com/spring-security/spring-boot-oauth2-jwt-example
http://www.tinmegali.com/en/2017/06/25/oauth2-using-spring/

**Resource Owner Password Credentials**
curl -v oauth2-client-id:oauth2-client-secret@localhost:8080/oauth/token -d "grant_type=password&username=shudong&password=password"
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsib2F1dGgyX3Jlc291cmNlX2lkIl0sInVzZXJfbmFtZSI6InNodWRvbmciLCJzY29wZSI6WyJyZWFkIiwid3JpdGUiXSwiZXhwIjoxNTM4OTA0NDM4LCJhdXRob3JpdGllcyI6WyJST0xFX0FETUlOIl0sImp0aSI6IjY4ZDRhNzRiLTAzYzMtNDQ0OS1hMTZlLWU3MzcyYjE0MDUxNSIsImNsaWVudF9pZCI6Im9hdXRoMi1jbGllbnQtaWQifQ.7MfsB601zfXyAO-VnLtfcyx76m-IAtjjWpHGQrQhdvo",
    "token_type": "bearer",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsib2F1dGgyX3Jlc291cmNlX2lkIl0sInVzZXJfbmFtZSI6InNodWRvbmciLCJzY29wZSI6WyJyZWFkIiwid3JpdGUiXSwiYXRpIjoiNjhkNGE3NGItMDNjMy00NDQ5LWExNmUtZTczNzJiMTQwNTE1IiwiZXhwIjoxNTM4OTIyNDM4LCJhdXRob3JpdGllcyI6WyJST0xFX0FETUlOIl0sImp0aSI6ImFhMWJjMTMzLTdkMGUtNGY5Ny1hOWYwLTU3YmJiYjk0N2FmZSIsImNsaWVudF9pZCI6Im9hdXRoMi1jbGllbnQtaWQifQ.gmGGKPMk8x3iFMWJSBuakSRf7j44AWV67JEQF9UQMnQ",
    "expires_in": 3599,
    "scope": "read write",
    "jti": "68d4a74b-03c3-4449-a16e-e7372b140515"
}

curl -v oauth2-client-id:oauth2-client-secret@localhost:8080/oauth/token -d "grant_type=refresh_token&refresh_token={refresh_token}"

curl -v -H "Authorization: Bearer {access_token}" http://localhost:8080/api/admin
curl -v -H "Authorization: Bearer {access_token}" http://localhost:8080/api/user

**Authorization Code**
curl -v http://localhost:8080/oauth/authorize -d "response_type=code&client_id=oauth2-client-id&redirect_uri=CALLBACK_URL&scope=read"

**Implicit**
curl -v http://localhost:8080/oauth/authorize -d "response_type=token&client_id=oauth2-client-id&redirect_uri=CALLBACK_URL&scope=read"

**Client Credentials Flow**
curl -v http://localhost:8080/oauth/token -d "grant_type=client_credentials&client_id=oauth2-client-id&client_secret=oauth2-client-secret"