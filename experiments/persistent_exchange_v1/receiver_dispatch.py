"""Fixed real model routes after the user's explicit HY3 credit opt-in."""
from pathlib import Path
from .model_runtime import REPO

QUALIFICATION = REPO/'results/persistent_exchange_v1/billing/paid_ask_qualification_01/envelope.rechecked.v2.json'


def answer_receiver(platform, db_path, batch_id, questions, job_dir):
    if platform == 'hy3':
        from .receiver_paid_runtime import answer_paid_hy3
        return answer_paid_hy3(db_path,batch_id,questions,job_dir,QUALIFICATION)
    if platform == 'flash':
        from .receiver_runtime import answer_receiver as sdk_receiver
        return sdk_receiver(platform,db_path,batch_id,questions,job_dir)
    raise ValueError('registered_receiver_platform_required')
