(function () {
  const statusBox = document.getElementById('loc-status');
  const retryBtn = document.getElementById('loc-retry');
  const submitBtn = document.getElementById('submit-btn');
  const latEl = document.getElementById('lat');
  const lngEl = document.getElementById('lng');
  const accEl = document.getElementById('accuracy');
  const fileInput = document.getElementById('media');
  const previews = document.getElementById('previews');
  const MAX_FILES = 5, MAX_BYTES = 60 * 1024 * 1024;

  function setState(cls, text) {
    statusBox.className = 'loc ' + cls;
    statusBox.textContent = text;
  }

  function onPosition(pos) {
    latEl.value = pos.coords.latitude;
    lngEl.value = pos.coords.longitude;
    accEl.value = pos.coords.accuracy;
    setState('loc-ok', 'Location captured: ' + pos.coords.latitude.toFixed(5) + ', ' +
      pos.coords.longitude.toFixed(5) + ' (accuracy about ' + Math.round(pos.coords.accuracy) + ' m)');
    retryBtn.hidden = true;
    submitBtn.disabled = false;
  }

  function onError(err) {
    const msgs = {
      1: 'Location is blocked. Allow location access for this site in your browser settings, then try again.',
      2: 'Your device could not work out its location. Move to an open area and try again.',
      3: 'Finding your location took too long. Try again.'
    };
    setState('loc-bad', msgs[err.code] || 'Could not get your location.');
    retryBtn.hidden = false;
    submitBtn.disabled = true;
  }

  function locate() {
    if (!navigator.geolocation) {
      setState('loc-bad', 'This browser cannot share location. Use a recent Chrome, Edge, Firefox or Safari.');
      return;
    }
    setState('loc-wait', 'Finding your location...');
    retryBtn.hidden = true;
    navigator.geolocation.getCurrentPosition(onPosition, onError,
      { enableHighAccuracy: true, timeout: 20000, maximumAge: 0 });
  }

  retryBtn.addEventListener('click', locate);

  fileInput.addEventListener('change', function () {
    previews.innerHTML = '';
    const files = Array.from(fileInput.files);
    const total = files.reduce((s, f) => s + f.size, 0);
    if (files.length > MAX_FILES || total > MAX_BYTES) {
      alert('Choose up to ' + MAX_FILES + ' files, 60 MB in total.');
      fileInput.value = '';
      return;
    }
    files.forEach(function (f) {
      const url = URL.createObjectURL(f);
      const el = document.createElement(f.type.startsWith('video') ? 'video' : 'img');
      el.src = url;
      if (el.tagName === 'VIDEO') { el.muted = true; el.preload = 'metadata'; }
      previews.appendChild(el);
    });
  });

  locate();
})();
