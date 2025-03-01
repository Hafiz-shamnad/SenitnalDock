document.addEventListener("DOMContentLoaded", () => {
    const scanButton = document.getElementById("scan-image");
    const scanOutput = document.getElementById("scan-output");
    const reportButton = document.getElementById("generate-report");

    async function fetchStats() {
        try {
            let response = await fetch('/monitor');
            let data = await response.json();

            if (data.error) {
                document.getElementById('stats').innerHTML = `<p style="color: red;">Error: ${data.error}</p>`;
                return;
            }

            let table = `<table border="1">
                <tr>
                    <th>Container</th>
                    <th>CPU</th>
                    <th>Memory Usage</th>
                    <th>Memory</th>
                    <th>Network</th>
                    <th>Block I/O</th>
                    <th>PIDs</th>
                </tr>`;

            data.forEach(container => {
                table += `<tr>
                    <td>${container.Container}</td>
                    <td>${container.CPUPerc}</td>
                    <td>${container.MemUsage}</td>
                    <td>${container.MemPerc}</td>
                    <td>${container.NetIO}</td>
                    <td>${container.BlockIO}</td>
                    <td>${container.PIDs}</td>
                </tr>`;
            });

            table += `</table>`;
            document.getElementById('stats').innerHTML = table;
        } catch (error) {
            document.getElementById('stats').innerHTML = `<p style="color: red;">Error fetching data</p>`;
        }
    }

    setInterval(fetchStats, 5000); // Refresh stats every 5 seconds
    async function fetchStats() {
        try {
            let response = await fetch('/monitor');
            let data = await response.json();

            if (data.error) {
                document.getElementById('stats').innerHTML = `
                    <div class="alert alert-danger" role="alert">
                        Error: ${data.error}
                    </div>`;
                return;
            }

            let table = `<table class="table table-striped table-hover">
                <thead class="thead-dark">
                    <tr>
                        <th>Container</th>
                        <th>CPU</th>
                        <th>Memory Usage</th>
                        <th>Memory</th>
                        <th>Network</th>
                        <th>Block I/O</th>
                        <th>PIDs</th>
                    </tr>
                </thead>
                <tbody>`;

            data.forEach(container => {
                table += `<tr>
                    <td>${container.Container}</td>
                    <td>${container.CPUPerc}</td>
                    <td>${container.MemUsage}</td>
                    <td>${container.MemPerc}</td>
                    <td>${container.NetIO}</td>
                    <td>${container.BlockIO}</td>
                    <td>${container.PIDs}</td>
                </tr>`;
            });

            table += `</tbody></table>`;
            document.getElementById('stats').innerHTML = table;
        } catch (error) {
            document.getElementById('stats').innerHTML = `
                <div class="alert alert-danger" role="alert">
                    Error fetching data.
                </div>`;
        }
    }

    setInterval(fetchStats, 5000);

    // Trigger Trivy scan
    scanButton.addEventListener("click", async () => {
        const imageName = document.getElementById("image-name").value;
        if (!imageName) {
            alert("Please enter a Docker image name.");
            return;
        }

        scanOutput.textContent = "Scanning...";

        try {
            const response = await fetch("/scan", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ image_name: imageName }),
            });

            if (!response.ok) throw new Error("Failed to perform scan.");

            const result = await response.json();
            scanOutput.textContent = JSON.stringify(result, null, 2);
        } catch (error) {
            scanOutput.textContent = `Error: ${error.message}`;
        }
    });

    // Trigger report generation
    reportButton.addEventListener("click", async () => {
        const scanOutputText = scanOutput.textContent;
        if (!scanOutputText || scanOutputText.startsWith("Error") || scanOutputText === "Scanning...") {
            alert("Run a successful scan first!");
            return;
        }

        const cveList = JSON.parse(scanOutputText);

        try {
            const response = await fetch("/generate-report", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ cve_list: cveList }), // Pass actual CVE list
            });

            if (!response.ok) throw new Error("Failed to generate report.");

            const result = await response.json();
            alert(`Report generated! Download it from: ${result.pdf}`);
        } catch (error) {
            alert(`Error: ${error.message}`);
        }
    });
});
document.addEventListener("DOMContentLoaded", function () {
    const containerList = document.getElementById("container-list");
    const systemLogs = document.getElementById("system-logs");
    const refreshLogsBtn = document.getElementById("refresh-logs");
    
    let selectedContainerId = null;
    let ws = null;

    // Fetch running containers
    function fetchContainers() {
        fetch("/containers")
            .then(response => response.json())
            .then(data => {
                containerList.innerHTML = "";
                if (data.error) {
                    containerList.innerHTML = `<li class="list-group-item text-danger">${data.error}</li>`;
                    return;
                }

                data.forEach(container => {
                    const listItem = document.createElement("li");
                    listItem.className = "list-group-item list-group-item-action";
                    listItem.textContent = container.Name || container.Names[0];
                    listItem.setAttribute("data-container-id", container.ID);

                    listItem.addEventListener("click", function () {
                        document.querySelectorAll(".list-group-item").forEach(item => item.classList.remove("active"));
                        listItem.classList.add("active");

                        selectedContainerId = container.ID;
                        connectWebSocket(selectedContainerId);
                    });

                    containerList.appendChild(listItem);
                });
            })
            .catch(error => {
                containerList.innerHTML = `<li class="list-group-item text-danger">Error: ${error.message}</li>`;
                console.error("Error fetching containers:", error);
            });
    }

    function connectWebSocket(containerId) {
        if (ws) {
            ws.close();
        }
    
        ws = new WebSocket(`ws://127.0.0.1:5000/logs`);
    
        ws.onopen = function () {
            ws.send(JSON.stringify({ container: containerId }));
            systemLogs.innerHTML = "";
        };
    
        ws.onmessage = function (event) {
            let logEntry = document.createElement("div");
            logEntry.textContent = `${event.data}`;
            logEntry.className = "log-entry";
    
            systemLogs.appendChild(logEntry);
    
            if (systemLogs.childElementCount > 20) {
                systemLogs.removeChild(systemLogs.firstChild);
            }
        };
    
        ws.onerror = function (error) {
            console.error("WebSocket error:", error);
        };
    
        ws.onclose = function () {
            console.log("WebSocket closed");
        };
    }

    refreshLogsBtn.addEventListener("click", function () {
        if (selectedContainerId) {
            systemLogs.innerHTML = ""; 
            connectWebSocket(selectedContainerId); // Reconnect to fetch new logs
        }
    });

    fetchContainers();
});
