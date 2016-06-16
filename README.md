# CC3200_AWS_IoT

This application allows the users to input a text message to the CC3200 launchpad through the AT&T S10-S3 <br />
Remote Control and send the message to multiple phone numbers. It uses the RESTful api to connect with <br />
Amazon Web Services. When the users press the buton MUTE on their remote control, the message will be <br />
enclosed in a POST method that will be sent to the AWS. On AWS side, a rule will be triggered that will <br />
use SNS service to send the text message to multiple phone numbers. <br />
