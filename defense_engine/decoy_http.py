from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict

app = FastAPI(title="StealthMesh Decoy Service")


class DecoyEvent(BaseModel):
    node_id: str       # defender node receiving the attack
    suspect: str       # attacker id (node or IP)
    msg_type: str
    message: Dict[str, Any]


@app.post("/decoy")
def receive_decoy(event: DecoyEvent):
    # For now: just log. In future: store in DB, trigger more analysis, etc.
    print(
        f"[DECOY-SVC] Node={event.node_id} suspect={event.suspect} "
        f"type={event.msg_type} message={event.message}"
    )
    # You could also return fake data here, e.g. pretend to be a file server.
    return {"ok": True, "note": "Decoy accepted"}
