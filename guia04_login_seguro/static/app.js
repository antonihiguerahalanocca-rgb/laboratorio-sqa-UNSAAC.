// 1) Ojito: mostrar / ocultar contraseña
var OJO = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
var OJO_TACHADO = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
document.querySelectorAll(".ojo").forEach(function (boton) {
  boton.innerHTML = OJO;
  boton.addEventListener("click", function () {
    var input = boton.previousElementSibling;
    var oculto = input.type === "password";
    input.type = oculto ? "text" : "password";
    boton.innerHTML = oculto ? OJO_TACHADO : OJO;
    boton.setAttribute("aria-label", oculto ? "Ocultar contraseña" : "Mostrar contraseña");
  });
});

// Confirmación antes de eliminar una tarea
document.querySelectorAll("form[data-confirmar]").forEach(function (f) {
  f.addEventListener("submit", function (e) {
    if (!confirm(f.getAttribute("data-confirmar"))) e.preventDefault();
  });
});

// 2) Validación del correo mientras escribe
var correo = document.getElementById("correo");
var msgCorreo = document.querySelector('[data-msg="correo"]');
if (correo && msgCorreo) {
  correo.addEventListener("input", function () {
    var ok = /^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$/.test(correo.value);
    msgCorreo.className = "msg " + (correo.value === "" ? "" : ok ? "bien" : "error");
    msgCorreo.textContent = correo.value === "" ? "" : ok ? "Correo válido ✓" : "Correo no válido. Ejemplo: luis.flores@gmail.com";
  });
}

// 3) Medidor de seguridad de la contraseña (rojo → naranja → verde)
var pass = document.querySelector("[data-fuerza]");
if (pass) {
  var fuerza = document.querySelector(".fuerza");
  var segmentos = document.querySelectorAll(".segmentos span");
  var nivel = document.querySelector(".nivel");
  var reglas = {
    largo: function (v) { return v.length >= 12; },
    minus: function (v) { return /[a-z]/.test(v); },
    mayus: function (v) { return /[A-Z]/.test(v); },
    numero: function (v) { return /\d/.test(v); },
    especial: function (v) { return /[^A-Za-z0-9]/.test(v); }
  };

  pass.addEventListener("input", function () {
    var v = pass.value, cumple = 0;
    Object.keys(reglas).forEach(function (r) {
      var ok = reglas[r](v);
      document.querySelector('[data-req="' + r + '"]').classList.toggle("ok", ok);
      if (ok) cumple++;
    });

    var texto, clase, llenos;
    if (cumple <= 2) { texto = "Débil"; clase = "debil"; llenos = 1; }
    else if (cumple === 3) { texto = "Regular"; clase = "media"; llenos = 2; }
    else if (cumple === 4) { texto = "Buena"; clase = "media"; llenos = 3; }
    else { texto = "Excelente"; clase = "fuerte"; llenos = 4; }

    // solo se muestra mientras hay algo escrito
    fuerza.classList.toggle("visible", v.length > 0);
    fuerza.className = "fuerza " + clase + (v.length ? " visible" : "");
    segmentos.forEach(function (s, i) { s.classList.toggle("lleno", i < llenos); });
    nivel.textContent = "Seguridad: " + texto;
    compararConfirmacion();
  });

  // 4) ¿Coinciden las contraseñas?
  var confirmar = document.getElementById("confirmar");
  var msgConf = document.querySelector('[data-msg="confirmar"]');
  function compararConfirmacion() {
    if (!confirmar.value) { msgConf.textContent = ""; return; }
    var igual = confirmar.value === pass.value;
    msgConf.className = "msg " + (igual ? "bien" : "error");
    msgConf.textContent = igual ? "Las contraseñas coinciden ✓" : "Las contraseñas no coinciden.";
  }
  confirmar.addEventListener("input", compararConfirmacion);
}
