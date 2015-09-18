import time
from itsdangerous import Signer
import base64
import json



class User():
    def __init__(secret_key):
        #initialize signer
        self.s = Signer(secret_key)
        

    def deserialize(self,request):
        #it runs in framework BEFORE_REQUEST function
        self.cookies = request.cookies
        #check stat in cookie and verify it
        stat_str = self.cookies.get('stat')
        stat_signature = self.cookies.get('stat_signature')
        stat_token = stat_str+'.'+stat_signature
        
        if stat_str==None or self.s.validate(stat_token)==False:
            self.create_new_stat(request)

        #if validation success
        self.stat = json.loads(stat_str)        

        #add actual IP for checking log_token
        self.stat['ip'] = request.environ['SERVER_NAME']


    def serialize(self,response):
        #it runs in framework AFTER_REQUEST function
        stat_str = json.dumps(self.stat)
        self.stat_signature = s.sign(stat_str).split('.')[1]
        response.set_cookie('stat',stat_str)
        response.set_cookie('stat_signature',stat_signature)

        if self.log_token!=None:
            response.set_cookie('log_token',self.log_token)


    def create_new_stat(self,request):
        self.stat = {}
        
        self.stat['ip'] = request.environ['SERVER_NAME']
        self.stat['first_reg'] = int(time.time())
        self.stat['kolvo_visits'] = 1
        self.stat['user_id'] = 'yap'+str(int(time.time()))

    def check_auth(self,roles):
        log_token = self.cookies.get('log_token')

        if log_token==None:
            return 'Error User:Not Login, Please Log IN'

        if self.s.validate(log_token)!=True:
            return 'Error User:Not Valid Stat Token. Please, Log IN'

        
        self.session = self.get_json(log_token)

        if self.session['ip']!=self.stat['ip']:
            return 'Error User:Not valid IP. Please, log IN'
        
        
        if (int(time.time()) - int(self.session['ts']))>int(self.session['live_time']):
            return 'Error User:Session nor fresh, please Log IN'

        return True

    def login(self,user_name,user_pass, token_live_time=86400):
        #if user id in db and pass is equal md5 with secret
        #change user id in stat
        self.log_token = self.gen_token()
        #return new token
        pass
        
        
    def gen_token(self,user_id,user_roles,user_ip,token_live_time):
        self.session = {}
        self.session['user_id'] = user_id
        self.session['ts'] = int(time.time())
        self.session['roles'] = user_roles
        self.session['live_time'] = token_live_time
        self.session['ip'] = self.stat['ip']

        #create JSON from dict and compress
        j = json.dumps(self.session)
        j64 = base64.b64encode(j)

        #create signature
        j64_sign = self.s.sign(j64)    
    
        return j64_sign
    
    def get_json(self,token):
        if self.s.validate(token)!=True:
            return 'Error User: not valid Log Token'
        
        jb64 = self.s.unsign(token)
        j = base64.b64decode(jb64)
        j = json.loads(j)
        return j
        


    
def help():
    print '''

    User class

    app.user = User()
    app.user.deserialize(request)
        //chech signature (included in stat JSON) and generally stat JSON
        //if succes - return User object with stat dict.
        //if fail - run self.create_new_user(request) to generate new stat json
        in any case - deserialize returns user object with json dict

    
    
        //pass request container with para to User Class. User class determine
        //if request.COOKIE contains user_id

    app.user.create_new(request)
        //returns new user object with all data based on 


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

    json_dict = pl.get_json(token)
    pl.check_token(token,request_ob)
        :token = string
        :reqiest_obj - request, to retrive environ and user ip from IT
    

'''
