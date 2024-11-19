build container:
docker build -t proj .

run container:
docker run --privileged --device /dev/fuse -it proj
	-If user has an encrypted directory to mount, add this argument: -v /path/to/encrypted/dir:/app/str
	
download encrypted filesystem:	
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <container-id>
wget http://<container-ip>:8080/filename
