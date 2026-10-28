from pydantic_settings import BaseSettings, SettingsConfigDict
class Settings(BaseSettings):
    app_env:str="development"
    database_url:str="postgresql+psycopg://arena:arena_dev_password@localhost:5432/arena"
    frontend_origin:str="http://localhost:5173"
    jwt_secret:str="dev-secret-change-before-production-123456789"
    jwt_expire_minutes:int=60
    admin_email:str="admin@example.com"
    smtp_host:str=""
    smtp_port:int=587
    smtp_username:str=""
    smtp_password:str=""
    smtp_from:str=""
    razorpay_key_id:str=""
    razorpay_key_secret:str=""
    razorpay_webhook_secret:str=""
    model_config=SettingsConfigDict(env_file="../.env", extra="ignore", case_sensitive=False)
settings=Settings()
