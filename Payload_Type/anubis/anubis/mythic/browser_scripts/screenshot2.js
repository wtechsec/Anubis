function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    } else if(task.completed){
        if(responses.length > 0){
            let data = JSON.parse(responses[0].replace(/'/g, '"'));
            return {"screenshot":[{
                "agent_file_id": data["file_id"],
                "variant": "contained",
                "name": "View Screenshot 2"
            }]};
        } else {
            return {"plaintext": "No data to display..."}
        }
    } else if(task.status === "processed"){
        if(responses.length > 0){
            let data = JSON.parse(responses[0]);
            return {"screenshot":[{
                "agent_file_id": data["file_id"],
                "variant": "contained",
                "name": "View Partial Screenshot 2"
            }]};
        }
        return {"plaintext": "No data yet..."}
    } else {
        return {"plaintext": "No response yet from agent..."}
    }
}

