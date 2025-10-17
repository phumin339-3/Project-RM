// welcome.js — toggle light/dark แบบจำค่า
(() => {
    const $ = (id) => document.getElementById(id);
  
    function applyTheme(mode){
      if(mode === "dark") document.body.classList.add("dark");
      else document.body.classList.remove("dark");
      const t = $("themeToggle");
      if (t) t.checked = (mode === "dark");
    }
    function initTheme(){
      const saved = localStorage.getItem("pd_theme") || "light";
      applyTheme(saved);
      $("themeToggle")?.addEventListener("change", (e) => {
        const mode = e.currentTarget.checked ? "dark" : "light";
        localStorage.setItem("pd_theme", mode);
        applyTheme(mode);
      });
    }
  
    document.addEventListener("DOMContentLoaded", initTheme);
  })();
  