# INSE6130_AutoContainerSecAssessment

A container image that tests the container environment by execute a simple bash script.

To use it, build the image from the Dockerfile using this command inside the repository :
```
docker build -t auto_container_sec_assessment .
```
Then you can check if your container environment is vulnerable to our presented vulnerabilities by running this image with your wanted privileges. 
Example:
```
docker run -it --rm --name DinD --volume /var/run/docker.sock:/var/run/docker.sock auto_container_sec_assessment

Automated script testing whether our presented container escape vulnerabilities can be exploited

Directory created successfully

/!\ This container is vulnerable to DinD / DooD attack. To mitigate, do not allow access to the docker socket inside a container. Consider using tools like Kaniko or Buildah for building Docker images inside a container.
```