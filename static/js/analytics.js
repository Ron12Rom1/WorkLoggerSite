(() => {
  const payloadScript = document.getElementById('analytics-payload');
  if (!payloadScript) return;
  let data;
  try {
    data = JSON.parse(payloadScript.textContent || '{}');
  } catch (e) {
    console.error('Invalid analytics payload', e);
    return;
  }

  const {
    monthly_labels: monthlyLabels = [],
    monthly_hours: monthlyHours = [],
    monthly_wages: monthlyWages = [],
    monthly_tips: monthlyTips = [],
    monthly_pay: monthlyPay = [],
    position_labels: positionLabels = [],
    position_hours: positionHours = [],
    position_pay: positionPay = [],
    daily_labels: dailyLabels = [],
    daily_pay: dailyPay = [],
  } = data;

  const el = (id) => document.getElementById(id);
  const safeCtx = (id) => {
    const c = el(id);
    return c && c.getContext ? c : null;
  };

  const monthlyPayEl = safeCtx('monthlyPay');
  if (monthlyPayEl) {
    new Chart(monthlyPayEl, {
      type: 'bar',
      data: { labels: monthlyLabels, datasets: [{ label: 'Pay ($)', data: monthlyPay, backgroundColor: '#0d6efd' }] },
      options: { responsive: true, plugins: { legend: { display: true } }, scales: { y: { beginAtZero: true } } }
    });
  }

  const monthlyBreakdownEl = safeCtx('monthlyBreakdown');
  if (monthlyBreakdownEl) {
    new Chart(monthlyBreakdownEl, {
      type: 'line',
      data: {
        labels: monthlyLabels,
        datasets: [
          { label: 'Hours', data: monthlyHours, borderColor: '#6c757d', backgroundColor: 'rgba(108,117,125,.2)', tension: .2 },
          { label: 'Wages ($)', data: monthlyWages, borderColor: '#198754', backgroundColor: 'rgba(25,135,84,.2)', tension: .2 },
          { label: 'Tips ($)', data: monthlyTips, borderColor: '#ffc107', backgroundColor: 'rgba(255,193,7,.2)', tension: .2 },
        ]
      },
      options: { responsive: true, plugins: { legend: { display: true } }, scales: { y: { beginAtZero: true } } }
    });
  }

  const dailyTrendEl = safeCtx('dailyTrend');
  if (dailyTrendEl) {
    new Chart(dailyTrendEl, {
      type: 'line',
      data: { labels: dailyLabels, datasets: [{ label: 'Daily Pay ($)', data: dailyPay, borderColor: '#fd7e14', backgroundColor: 'rgba(253,126,20,.2)', tension: .2 }] },
      options: { responsive: true, plugins: { legend: { display: true } }, scales: { y: { beginAtZero: true } } }
    });
  }

  const byPositionPayEl = safeCtx('byPositionPay');
  if (byPositionPayEl) {
    new Chart(byPositionPayEl, {
      type: 'bar',
      data: { labels: positionLabels, datasets: [{ label: 'Total Pay ($)', data: positionPay, backgroundColor: '#6610f2' }] },
      options: { indexAxis: 'y', responsive: true, plugins: { legend: { display: true } }, scales: { x: { beginAtZero: true } } }
    });
  }

  const byPositionHoursEl = safeCtx('byPositionHours');
  if (byPositionHoursEl) {
    new Chart(byPositionHoursEl, {
      type: 'bar',
      data: { labels: positionLabels, datasets: [{ label: 'Hours', data: positionHours, backgroundColor: '#20c997' }] },
      options: { indexAxis: 'y', responsive: true, plugins: { legend: { display: true } }, scales: { x: { beginAtZero: true } } }
    });
  }
})();


