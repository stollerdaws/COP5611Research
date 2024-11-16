FROM python:3.12

COPY requirements.txt /app/requirements.txt
COPY filesys.py /app/filesys.py
RUN apt-get update 
WORKDIR /app
RUN apt-get install -y fuse
RUN pip install -r requirements.txt
RUN mkdir /app/data
COPY start.sh /app/start.sh
CMD ["/app/start.sh"]

