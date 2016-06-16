# CC3200_AWS_IoT

This application allows the users to input a text message to the CC3200 launchpad through the AT&T S10-S3 Remote Control <br />
and send the message to multiple phone numbers. It uses the RESTful api to connect with Amazon Web Services. When the <br />
users press the buton MUTE on their remote control, the message will be enclosed in a POST method that will be sent to the <br />
AWS. On AWS side, a rule will be triggered that will use SNS service to send the text message to multiple phone numbers. <br />
