// document.getElementById('fileInput').addEventListener('change', function(event) {
//     const file = event.target.files[0];
//     const validTypes = ['image/png', 'image/jpeg', 'image/svg+xml'];

//     // Перевірка наявності файлу та його типу
//     if (file && validTypes.includes(file.type)) {
//         const img = document.createElement('img');
//         img.src = URL.createObjectURL(file);
//         img.width = 100; // Задайте ширину
//         img.height = 100; // Задайте висоту
//         document.getElementById('avatarContainer').innerHTML = ''; // Очистка контейнера
//         document.getElementById('avatarContainer').appendChild(img); // Додати зображення
//     } else {
//         alert('Будь ласка, виберіть файл формату PNG, JPG або SVG.');
//     }
// });