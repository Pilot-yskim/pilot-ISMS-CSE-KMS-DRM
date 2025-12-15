# Node.js 18 버전 사용
FROM node:18-slim

# 작업 폴더 생성
WORKDIR /usr/src/app

# 의존성 설치
COPY package*.json ./
RUN npm install --only=production

# 소스 코드 복사
COPY . .

# 포트 설정 및 실행
ENV PORT 8080
CMD [ "npm", "start" ]
