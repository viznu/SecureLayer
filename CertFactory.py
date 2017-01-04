
def getRootCert():
	return open("CertificateBank/20164_signed.cert").read()

def getPrivateKeyForAddr(addr):
  with open("CertificateBank/324_2_private") as f:
    return f.read()

def getCertsForAddr(addr):
  chain = []
  with open("CertificateBank/324_2_signed.cert") as f:
    chain.append(f.read())
  with open("CertificateBank/vishnun_signed.cert") as f:
    chain.append(f.read())
  return chain
