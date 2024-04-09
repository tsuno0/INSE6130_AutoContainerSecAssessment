FROM ubuntu
COPY autoContainerSecAssessment.sh /autoContainerSecAssessment.sh
RUN chmod +x /autoContainerSecAssessment.sh
CMD /autoContainerSecAssessment.sh