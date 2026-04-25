1. install ollama https://ollama.com/download/windows and in cmd install `ollama pull qwen2.5-coder:14b`
2. in main directory in project start server - `uvicorn main:app --host 0.0.0.0 --port 8080 --reload`
3. go to `FartSuite_agent/` and start agent - `go run main.go` 
