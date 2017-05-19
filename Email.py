#!/usr/bin/python
# -*- coding: utf-8 -*-

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
import smtplib
from os.path import basename

mail_account = 'mail_account'
mail_passwd = 'mail_passwd'
smtp_server = 'smtp_server'


MAIL_CONFIG = {
    mail_account:'lashwang@outlook.com',
    mail_passwd:'meimei1985',
    smtp_server:'smtp-mail.outlook.com:587'
}




class Email(object):
    def __init__(self):
        self.smtp_server = MAIL_CONFIG[smtp_server]
        self.mail_account = MAIL_CONFIG[mail_account]
        self.mail_passwd = MAIL_CONFIG[mail_passwd]

    def send(self,recipients,subject,content,files=None):
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = self.mail_account
        msg['To'] = ", ".join(recipients)
        msg['Date'] = formatdate(localtime=True)

        msg.attach(MIMEText(content, _subtype='plain', _charset='utf-8'))
        for f in files or []:
            with open(f, "rb") as fil:
                part = MIMEApplication(
                    fil.read(),
                    Name=basename(f)
                )
                part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
                msg.attach(part)

        server = smtplib.SMTP(self.smtp_server)
        # server.set_debuglevel(1)
        server.ehlo()
        server.starttls()
        server.login(self.mail_account, self.mail_passwd)
        server.ehlo()
        server.sendmail(self.mail_account,recipients,msg.as_string())
        server.close()
