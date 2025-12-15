# 가볍고 안정적인 Node.js 18 슬림 버전 사용
FROM node:18-slim

# 작업 디렉토리 생성
WORKDIR /usr/src/app

# 의존성 파일 복사 및 설치 (캐시 효율성 증대)
COPY package*.json ./
RUN npm install --only=production

# 소스 코드 복사
COPY . .

# Cloud Run 기본 포트인 8080 개방
ENV PORT 8080
EXPOSE 8080

# 앱 실행
CMD [ "npm", "start" ]
