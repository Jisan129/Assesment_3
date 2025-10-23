-- ============================================
-- DROP EXISTING TABLES (if recreating)
-- ============================================
DROP TABLE IF EXISTS bookings;
DROP TABLE IF EXISTS galleries;
DROP TABLE IF EXISTS users;

-- ============================================
-- 1. USERS TABLE
-- ============================================
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL,
    user_type ENUM('admin', 'photographer', 'customer') DEFAULT 'customer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- 2. GALLERIES TABLE
-- ============================================
CREATE TABLE galleries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    photographer_id INT NOT NULL,
    title VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    image_url VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (photographer_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================
-- 3. BOOKINGS TABLE
-- ============================================





-- After registering photographers, insert their galleries
-- Check photographer IDs first:
SELECT id, username FROM users WHERE user_type = 'photographer';

-- Then insert galleries (replace IDs accordingly)
INSERT INTO galleries (photographer_id, title, description, price, image_url) VALUES
-- For first photographer
((SELECT id FROM users WHERE username='john_photography'), 'Wedding Photography', 'Full wedding coverage', 2500.00, 'https://images.unsplash.com/photo-1519741497674-611481863552?w=500'),
((SELECT id FROM users WHERE username='john_photography'), 'Portrait Session', 'Professional portraits', 299.00, 'https://images.unsplash.com/photo-1531746020798-e6953c6e8e04?w=500'),

-- For second photographer
((SELECT id FROM users WHERE username='sarah_shoots'), 'Newborn Photography', 'Newborn photos', 450.00, 'https://images.unsplash.com/photo-1515488042361-ee00e0ddd4e4?w=500'),
((SELECT id FROM users WHERE username='sarah_shoots'), 'Event Photography', 'Event coverage', 800.00, 'https://images.unsplash.com/photo-1511578314322-379afb476865?w=500');