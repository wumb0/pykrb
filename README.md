Pykrb
=====
This is a proof of concept and not actually compatible with real Kerberos. It was used to learn how kerberos works. It works like kerberos but may not be entirely secure :)<br>
It was meant to bring kerberos-like authentication to python with ease.<br>
The KDC should always be registered as id 0 in your kdc db.<br>
To register import register from pykrb.utils and then specify the DB file, your name, password, realm, and optionally whether you want to export a keyfile or not<br>
All services and users need to be in the KDC or auth will not work.
