
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()

# Remove all past jobs
scheduler.remove_all_jobs()

# Recreate the scheduler object
scheduler = BackgroundScheduler()
