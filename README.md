# 톡온(TalkOn)

닉네임으로 상대방을 찾아 1:1 대화를 나누는 실시간 채팅 앱입니다.

## 포함 기능

- 회원가입 / 로그인 / 로그아웃
- 닉네임 중복 방지
- 비밀번호 bcrypt 해시 저장
- 닉네임 검색 후 1:1 채팅
- 실시간 메시지 / 입력 중 표시 / 온라인 상태
- 회원정보, 세션, 채팅 기록을 PostgreSQL에 영구 저장
- Render Web Service + Render Postgres 배포 지원

## Render 배포

### Web Service
- Type: Web Service
- Language: Node
- Build Command: `npm install`
- Start Command: `npm start`

### PostgreSQL
1. Render에서 **New → Postgres**로 데이터베이스를 만듭니다.
2. 데이터베이스와 Web Service가 같은 Render 계정/리전에 있도록 합니다.
3. PostgreSQL의 **Connect**에서 **Internal Database URL**을 복사합니다.
4. Web Service의 **Environment**에 다음 변수를 추가합니다.
   - Key: `DATABASE_URL`
   - Value: 복사한 Internal Database URL
5. 저장하면 자동 재배포됩니다.

앱이 처음 시작될 때 필요한 테이블을 자동으로 생성합니다.

> Render Free Postgres는 현재 30일 후 만료되는 제한이 있습니다. 장기간 데이터를 보존하려면 만료 전에 유료 Postgres로 업그레이드해야 합니다.

## 로컬 실행

로컬에서도 PostgreSQL을 준비하고 `DATABASE_URL`을 설정한 후:

```bash
npm install
npm start
```

으로 실행합니다.
