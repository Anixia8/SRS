FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
EXPOSE 8080
CMD ["bash","-lc","streamlit run dashboard.py --server.port=${PORT:-8080} --server.address=0.0.0.0"]
