import time
from itsdangerous import Signer
import base64
import json



class Pylog():
    
    def __init__(self,token_live_time,secret_key):
        self.token_live_time = token_live_time
        self.secret_key = secret_key
        self.s = Signer(self.secret_key)


        
    def gen_token(self,user_id,user_roles,user_ip):
        session = {}
        session['user_id'] = user_id
        session['ts'] = int(time.time())
        session['roles'] = user_roles
        session['live_time'] = self.token_live_time
        session['ip'] = user_ip

        #create JSON from dict and compress
        j = json.dumps(session)
        j64 = base64.b64encode(j)

        #create signature
        j64_sign = self.s.sign(j64)    
    
        return j64_sign
    
    def get_json(self,token):
        if self.s.validate(token)!=True:
            return 'Error from Pylog: not valid token'
        
        jb64 = self.s.unsign(token)
        j = base64.b64decode(jb64)
        j = json.loads(j)
        return j
        

    def check_token(self,token):
        #checking if IP equal to current and check if token is FRESH
        if self.s.validate(token)!=True:
            return 'Error from Pylog: not valid token'
        j = self.get_json(token)
        return True
    
    
def help():
    print '''
    Pylog - my library for generating token which consits of JSON encoding with BASE64 and signed.
    JSON comprises data which can be used for further (in next requests) checking, as an instance
    ip - you can check Ip. So, if IP will be changing (modiles) - checking will be false.


    pl = Pylog(86400,'andrii')
        :token_live_time  - time for saving cookie (1 day = 86500 in sec)
        :secret_key
        
    token = pl.gen_token('3242',[admin,superadmin],'188.166.24.65')
        :user_id
        :user_roles - list with roles, views with this roles will be accessible for user
        :user_ip - it is using for checkig in next time

    

'''
