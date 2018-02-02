https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html
https://jamielinux.com/docs/openssl-certificate-authority/create-the-intermediate-pair.html
https://jamielinux.com/docs/openssl-certificate-authority/sign-server-and-client-certificates.html

http://www.eclipse.org/jetty/documentation/current/configuring-ssl.html

cat intermediate/certs/127.0.0.1.cert.pem intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > /tmp/chain.pem
openssl pkcs12 -export -inkey intermediate/private/127.0.0.1.key.pem -in /tmp/chain.pem -out /tmp/127.0.0.1.p12
keytool -importkeystore -srckeystore /tmp/127.0.0.1.p12 -srcstoretype PKCS12 -destkeystore jalla.jks

