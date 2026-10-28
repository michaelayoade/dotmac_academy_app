
    document.body.addEventListener('htmx:configRequest', function (evt) {
      var m = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
      if (m) { evt.detail.headers['x-csrf-token'] = m[1]; }
    });
  