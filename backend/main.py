from fastapi import FastAPI
app=FastAPI(title="AI-Powered Document Application")

@app.get("/")
async def confirmation():
    return "Backend running successfully!"