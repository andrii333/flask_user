# pylog
Lib for log-in in Flask

Simple generating token based on user ip,id, timestamp etc.

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

    
