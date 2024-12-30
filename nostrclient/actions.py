
def like_event( target_event_id,target_pubkey,content="+"):
    """
    publish event
    """

    event = {     "kind": 7,  
    "content": content,  
    "tags": [
        ["e", target_event_id],   
        ["p", target_pubkey]  
    ]}

    return event 

def reply_to_event(target_event_id, target_pubkey, content):
    """
  
    """
    event = {
        "kind": 1,  # 
        "content": content,
        
        "tags": [
            ["e", target_event_id],  
            ["p", target_pubkey]   
        ]
    }
    return event        

def follow_user(target_pubkey):
    """
 
    """
    event = {
        "kind": 3,   
        "content": "",  
         
        "tags": [
            ["p", target_pubkey]  
        ]
    }
    return event   

def create_post(content,tags=[]):
    """
 
    """
    event = {
        "kind": 1,  
        "content": content,
 
        "tags": [['client','nostrclient'],tags]  
    }
    return event