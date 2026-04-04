# Case Service\nHandles case creation and assignment workflows.



{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjA5MGJkY2UyLTE4YWItNDQyZS1hMTk4LTBhZjdhMDYwNDM4ZSIsIm5hbWUiOiJBa2VlbCIsImVtYWlsIjoiYWtlZWxAdGVzdC5jb20iLCJleHAiOjE3NzI1NTQ5MDd9.RIG8btlKkG0Btd5JyXOZvVhx6i4jqBtNTgrAVOqQOPUj8xOqUoB9eTA7OHXIouajgpeKFplTLQD3Gsoykkfcu6cpZ0fzBEzRSw8ieEDLXXbNw80fnPkxcVysk9peADgNHxt-ueY9hDX9x4qAZFjnbLCnMCLZ0Fj7md8UFuayve5kIFo94IPa2yL3bD7Fk-v3GkAo4SKXR6Ih3SFdh89PJU8R3gEcwPtFIZ8gMTg5KaZKkgO9fdqRS5VPKWMZUPXYpdv_inztqW-xzSZj3CocsbvjJVkgYFZ1MOXiLhMYfphmB_guNdlf2aJezpI-N6XHWxPsUdq21d1s4YM9-UFSxQ","user_id":"090bdce2-18ab-442e-a198-0af7a060438e","user_name":"Akeel"}


curl -X POST http://localhost:3003/evidence \
-H "Content-Type: application/json" \
-H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjA5MGJkY2UyLTE4YWItNDQyZS1hMTk4LTBhZjdhMDYwNDM4ZSIsIm5hbWUiOiJBa2VlbCIsImVtYWlsIjoiYWtlZWxAdGVzdC5jb20iLCJleHAiOjE3NzI1NTQ5MDd9.RIG8btlKkG0Btd5JyXOZvVhx6i4jqBtNTgrAVOqQOPUj8xOqUoB9eTA7OHXIouajgpeKFplTLQD3Gsoykkfcu6cpZ0fzBEzRSw8ieEDLXXbNw80fnPkxcVysk9peADgNHxt-ueY9hDX9x4qAZFjnbLCnMCLZ0Fj7md8UFuayve5kIFo94IPa2yL3bD7Fk-v3GkAo4SKXR6Ih3SFdh89PJU8R3gEcwPtFIZ8gMTg5KaZKkgO9fdqRS5VPKWMZUPXYpdv_inztqW-xzSZj3CocsbvjJVkgYFZ1MOXiLhMYfphmB_guNdlf2aJezpI-N6XHWxPsUdq21d1s4YM9-UFSxQ" \
-d '{
  "case_id": "b88f196c-abf5-45f1-b017-761b7eb538d0",
  "file_name": "fraud.pdf"
}'



❯ curl -X POST http://localhost:3003/evidence -H "Content-Type: application/json" -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjA5MGJkY2UyLTE4YWItNDQyZS1hMTk4LTBhZjdhMDYwNDM4ZSIsIm5hbWUiOiJBa2VlbCIsImVtYWlsIjoiYWtlZWxAdGVzdC5jb20iLCJleHAiOjE3NzI1NTQ5MDd9.RIG8btlKkG0Btd5JyXOZvVhx6i4jqBtNTgrAVOqQOPUj8xOqUoB9eTA7OHXIouajgpeKFplTLQD3Gsoykkfcu6cpZ0fzBEzRSw8ieEDLXXbNw80fnPkxcVysk9peADgNHxt-ueY9hDX9x4qAZFjnbLCnMCLZ0Fj7md8UFuayve5kIFo94IPa2yL3bD7Fk-v3GkAo4SKXR6Ih3SFdh89PJU8R3gEcwPtFIZ8gMTg5KaZKkgO9fdqRS5VPKWMZUPXYpdv_inztqW-xzSZj3CocsbvjJVkgYFZ1MOXiLhMYfphmB_guNdlf2aJezpI-N6XHWxPsUdq21d1s4YM9-UFSxQ" -d '{
  "case_id": "b88f196c-abf5-45f1-b017-761b7eb538d0",
  "file_name": "fraud.pdf"
}'
{"hash":"f5cbb3ad22f7f234d5d1839c15936aa9c655ab0cb25a43445785c732388d0393","status":"evidence created"}

<!-- 
1️⃣ User authentication (JWT)
2️⃣ Case creation & assignment
3️⃣ Evidence upload with hashing
4️⃣ Case validation before evidence upload
5️⃣ Evidence access tracking
6️⃣ Audit log creation (via audit service)
7️⃣ Secure API design
8️⃣ Schema-separated database -->