# CVE-2021-22911
Pre-Auth Blind NoSQL Injection leading to Remote Code Execution in Rocket Chat 3.12.1

- The getPasswordPolicy method is vulnerable to NoSQL injection attacks and does not require authentication/authorization. It can be used to take over accounts by leaking password reset tokens. Taking over an admin account leads to Remote Code Execution.

### Usage
```bash
python3 exploit.py -u "user@rocket.local" -a "admin@rocket.local" -t "http://rocket.local"
```

### Environment
- Tested on Rocket Chat 3.12.1
- Building your own test environment using docker :
```
docker run --name db -d mongo:3.6 --smallfiles --replSet rs0 --oplogSize 128
docker exec -ti db mongo --eval "printjson(rs.initiate())"
docker run --name rocketchat -p 80:3000 --link db --env ROOT_URL=http://localhost --env MONGO_OPLOG_URL=mongodb://db:27017/local -d rocket.chat:3.12.1

```

### Credits
- https://hackerone.com/reports/1130721 ( sonar source ) 
- https://blog.sonarsource.com/nosql-injections-in-rocket-chat

### Exploit-db
- Coming soon
