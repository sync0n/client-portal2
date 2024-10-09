document.getElementById('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    const response = await fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            'username': username,
            'password': password
        })
    });

    if (response.ok) {
        // Log into ThingsBoard in the background
        await fetch('/thingsboard_login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username: 'olde_puiestee84_22@thingsboard.org', password: 'kolde22' }),
        });

        window.location.href = '/';
    } else {
        alert('Login failed');
    }
});
