const form = document.getElementById('loginForm');
const siguienteBtn = document.getElementById('siguiente-btn');
const errorMessage = document.getElementById('error-message');
const successMessage = document.getElementById('success-message');
const inputs = [
    document.getElementById('email'),
    document.getElementById('password'),
    document.getElementById('codigo')
];

// Función para verificar si todos los campos están llenos
function verificarCampos() {
    return inputs.every(input => input.value.trim() !== '');
}

// Función para mostrar error en campos vacíos
function mostrarErroresCampos() {
    inputs.forEach(input => {
        if (input.value.trim() === '') {
            input.classList.add('error');
            setTimeout(() => {
                input.classList.remove('error');
            }, 500);
        }
    });
}

// Función para mover el botón
function moverBoton() {
    siguienteBtn.classList.add('moving');
    setTimeout(() => {
        siguienteBtn.classList.remove('moving');
    }, 500);
}

// Event listener para el botón
siguienteBtn.addEventListener('click', function(e) {
    e.preventDefault();
    
    // Ocultar mensajes previos
    errorMessage.classList.remove('show');
    successMessage.classList.remove('show');
    
    if (verificarCampos()) {
        // Si todos los campos están llenos
        successMessage.classList.add('show');
        siguienteBtn.style.background = 'linear-gradient(135deg, #28a745 0%, #20c997 100%)';
        siguienteBtn.textContent = '¡Completado!';
        
        // Aquí puedes agregar la lógica para proceder al siguiente paso
        setTimeout(() => {
            alert('¡Formulario enviado exitosamente!');
        }, 1000);
        
    } else {
        // Si faltan campos por llenar
        mostrarErroresCampos();
        moverBoton();
        errorMessage.classList.add('show');
    }
});

// Event listeners para remover el estado de error cuando el usuario empiece a escribir
inputs.forEach(input => {
    input.addEventListener('input', function() {
        this.classList.remove('error');
        errorMessage.classList.remove('show');
        
        // Resetear el botón si estaba en estado de éxito
        if (siguienteBtn.textContent === '¡Completado!') {
            siguienteBtn.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
            siguienteBtn.textContent = 'Siguiente';
            successMessage.classList.remove('show');
        }
    });
});

// Prevenir el envío tradicional del formulario
form.addEventListener('submit', function(e) {
    e.preventDefault();
});