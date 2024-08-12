document.getElementById('register-form').addEventListener('submit', async (event) => {
    event.preventDefault();

    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;

    try {
        const response = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });

        if (response.ok) {
            alert('Registration successful!');
        } else {
            alert('Registration failed.');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred.');
    }
});

document.getElementById('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();

    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });

        if (response.ok) {
            const { token } = await response.json();
            localStorage.setItem('token', token);
            alert('Login successful!');
            // Redirect or update UI as needed
        } else {
            alert('Login failed.');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred.');
    }
});
