const defaultChartColors = ['#66d9ff', '#4ca3ff', '#ff5c7a', '#ffb84d', '#5fe3b1'];

function setupCharts() {
  const chartEls = document.querySelectorAll('[data-chart]');
  if (!window.dashboardCharts || !chartEls.length) {
    return;
  }

  chartEls.forEach((element) => {
    const chartKey = element.dataset.chartSet;
    const config = window.dashboardCharts[chartKey];
    if (!config) return;

    const chartType = element.dataset.chart || 'bar';
    const options = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: { color: '#edf7ff' }
        }
      },
      scales: {
        x: {
          ticks: { color: '#9bb5c8' },
          grid: { display: false }
        },
        y: {
          ticks: { color: '#9bb5c8' },
          grid: { color: 'rgba(255,255,255,0.06)' }
        }
      }
    };

    new Chart(element, {
      type: chartType,
      data: {
        labels: config.labels,
        datasets: [{
          label: chartKey,
          data: config.values,
          backgroundColor: defaultChartColors,
          borderColor: '#66d9ff',
          borderWidth: 1,
          fill: chartType === 'line',
          tension: 0.35
        }]
      },
      options
    });
  });
}

document.addEventListener('DOMContentLoaded', setupCharts);
