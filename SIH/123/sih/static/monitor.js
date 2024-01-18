document.addEventListener("DOMContentLoaded", function () {
    // Function to fetch and update monitoring data
    function updateMonitoringData() {
        // Make an AJAX request to your Flask server
        fetch('/api/get_monitoring_data')
            .then((response) => response.json())
            .then((data) => {
                // Update the monitoring data on the page
                document.getElementById('monitoring-data').innerHTML = data.html;
            })
            .catch((error) => {
                console.error('Error fetching monitoring data:', error);
            });
    }

    // Call the updateMonitoringData function initially
    updateMonitoringData();

    // Schedule the function to run every 5 seconds (adjust the interval as needed)
    setInterval(updateMonitoringData, 5000);
});
