document.addEventListener("DOMContentLoaded", () => {
    const scanButton = document.getElementById("scan-image");
    const scanOutput = document.getElementById("scan-output");
    const reportButton = document.getElementById("generate-report");

    let containerThresholds = {};  // Store thresholds for each container

    async function updateContainers() {
        try {
            let response = await fetch('/monitor');
            let data = await response.json();
            let thresholdContainer = document.getElementById("threshold-container");

            if (data.error) {
                thresholdContainer.innerHTML = `<p style="color: red;">Error: ${data.error}</p>`;
                return;
            }

            thresholdContainer.innerHTML = ""; // Clear old content

            data.forEach(container => {
                let containerId = container.Container;

                // Set default threshold values if not already set
                if (!containerThresholds[containerId]) {
                    containerThresholds[containerId] = { cpu: 80, memory: 70 };
                }

                let containerHTML = `
                    <div class="mb-2 p-2 border rounded">
                        <strong>${containerId}</strong>
                        <label for="cpu-threshold-${containerId}" class="form-label mt-2">CPU Threshold (%)</label>
                        <input type="number" id="cpu-threshold-${containerId}" class="form-control"
                            value="${containerThresholds[containerId].cpu}">

                        <label for="mem-threshold-${containerId}" class="form-label mt-2">Memory Threshold (%)</label>
                        <input type="number" id="mem-threshold-${containerId}" class="form-control"
                            value="${containerThresholds[containerId].memory}">
                    </div>
                `;

                thresholdContainer.innerHTML += containerHTML;
            });
        } catch (error) {
            document.getElementById("threshold-container").innerHTML = `<p style="color: red;">Error fetching container list.</p>`;
        }
    }

    document.getElementById("set-thresholds").addEventListener("click", () => {
        let inputs = document.querySelectorAll("[id^='cpu-threshold-'], [id^='mem-threshold-']");

        inputs.forEach(input => {
            let containerId = input.id.split("-").slice(2).join("-");  // Extract container name from input ID
            let type = input.id.includes("cpu") ? "cpu" : "memory";
            containerThresholds[containerId][type] = input.value;
        });

        alert("Thresholds updated!");
    });

    async function fetchStats() {
        try {
            let response = await fetch('/monitor');
            let data = await response.json();
            let alertPanel = document.getElementById("alert-panel");

            if (data.error) {
                document.getElementById("stats").innerHTML = `<p style="color: red;">Error: ${data.error}</p>`;
                return;
            }

            let table = `<table class="table table-striped">
                <thead>
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

            alertPanel.innerHTML = "";  // Clear old alerts

            data.forEach(container => {
                let containerId = container.Container;
                let cpuUsage = parseFloat(container.CPUPerc.replace("%", ""));
                let memUsage = parseFloat(container.MemPerc.replace("%", ""));

                table += `<tr>
                    <td>${containerId}</td>
                    <td>${container.CPUPerc}</td>
                    <td>${container.MemUsage}</td>
                    <td>${container.MemPerc}</td>
                    <td>${container.NetIO}</td>
                    <td>${container.BlockIO}</td>
                    <td>${container.PIDs}</td>
                </tr>`;

                // Get per-container thresholds
                let cpuThreshold = containerThresholds[containerId]?.cpu || 80;
                let memThreshold = containerThresholds[containerId]?.memory || 70;

                if (cpuUsage > cpuThreshold) {
                    alertPanel.innerHTML += `<div class="alert alert-warning">
                        ⚠️ High CPU usage on ${containerId}: ${cpuUsage}%
                    </div>`;
                }
                
                if (memUsage > memThreshold) {
                    alertPanel.innerHTML += `<div class="alert alert-danger">
                        🔥 High Memory usage on ${containerId}: ${memUsage}%
                    </div>`;
                }
            });

            table += `</tbody></table>`;
            document.getElementById("stats").innerHTML = table;
        } catch (error) {
            document.getElementById("stats").innerHTML = `<p style="color: red;">Error fetching data</p>`;
        }
    }

    updateContainers();
    setInterval(updateContainers, 10000);  // Update the container list every 10 sec
    setInterval(fetchStats, 5000);  // Fetch stats every 5 sec

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


