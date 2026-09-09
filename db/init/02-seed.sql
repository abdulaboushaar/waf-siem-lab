-- Passwords: admin/admin123, alice/password1, bob/hunter2
-- bcrypt cost 10. Weak passwords on purpose so the replay harness can succeed.
INSERT INTO users (username, password_hash, role) VALUES
  ('admin', '$2y$10$WssLAjHFpP6XUKordYTHMePSQ9.NHUmgonpwbwAugpF5XlsrW6n5C', 'admin'),
  ('alice', '$2y$10$mP8BZPZYQ88/vivOApa8POU5A/ohoxOvE8J3Jc9pJQw/ZIqrsscXu', 'user'),
  ('bob',   '$2y$10$3P0BrWlO2LDSQSj8HNEcU.XadoZCIaSBKbPtNwXZr0dQe4J7Tz5/q', 'user');

-- Apostrophes are doubled to escape them here. Several names carry one on
-- purpose: they are the character that breaks naive concatenation, so a benign
-- search for "Builder's" must NOT be counted as an attack when we measure the
-- false positive rate at each paranoia level.
INSERT INTO products (name, category, price_cents, spec_file) VALUES
  ('AMD Ryzen 7 9800X3D',                       'CPU',        47999, 'ryzen-9800x3d.txt'),
  ('AMD Ryzen 9 9950X',                         'CPU',        59999, NULL),
  ('Intel Core Ultra 7 265K',                   'CPU',        39499, NULL),
  ('Intel Core Ultra 9 285K',                   'CPU',        58999, NULL),
  ('NVIDIA GeForce RTX 5080 Founders Edition',  'GPU',       109999, 'rtx5080.txt'),
  ('ASUS TUF Gaming RTX 5070 Ti',               'GPU',        84999, NULL),
  ('Sapphire Nitro+ Radeon RX 9070 XT',         'GPU',        72999, NULL),
  ('Corsair Vengeance DDR5-6000 32GB',          'Memory',     10999, NULL),
  ('G.Skill Trident Z5 Neo DDR5-6400 32GB',     'Memory',     13499, NULL),
  ('Crucial Pro DDR5-5600 64GB',                'Memory',     17999, NULL),
  ('Samsung 990 PRO 2TB NVMe',                  'Storage',    17999, 'samsung-990pro.txt'),
  ('WD Black SN850X 1TB NVMe',                  'Storage',     9499, NULL),
  ('Seagate IronWolf 8TB NAS Drive',            'Storage',    18999, NULL),
  ('Micro Center''s House Brand 4TB SSD',       'Storage',    19999, NULL),
  ('MSI MAG B850 Tomahawk WiFi',                'Motherboard',21999, NULL),
  ('Gigabyte X870 AORUS Elite',                 'Motherboard',25999, NULL),
  ('ASRock B860M Pro RS',                       'Motherboard',13999, NULL),
  ('Corsair RM850x 850W PSU',                   'Power',      14999, NULL),
  ('Seasonic Focus GX-750 (Builder''s Choice)', 'Power',      11999, NULL),
  ('be quiet! Pure Power 12 M 1000W',           'Power',      15999, NULL),
  ('Noctua NH-D15 G2 Air Cooler',               'Cooling',    14999, NULL),
  ('Arctic Liquid Freezer III 360',             'Cooling',    10499, NULL),
  ('O''Ryan Custom Sleeved Cable Kit',          'Cooling',     6999, NULL),
  ('Fractal Design North Mid Tower',            'Case',       13999, NULL),
  ('Lian Li O11 Dynamic EVO',                   'Case',       16999, NULL),
  ('Logitech G Pro X Superlight 2 (Editor''s Pick)', 'Peripherals', 15999, NULL),
  ('Keychron Q1 Pro Mechanical Keyboard',       'Peripherals',19999, NULL),
  ('SteelSeries Arctis Nova Pro Wireless',      'Peripherals',34999, NULL),
  ('Dell UltraSharp U2723QE 27" 4K Monitor',    'Display',    56999, NULL),
  ('LG UltraGear 27GR93U 27" 144Hz',            'Display',    64999, NULL),
  ('Ubiquiti UniFi U6 Pro Access Point',        'Network',    15999, NULL),
  ('TP-Link Archer AXE75 Router',               'Network',     9999, NULL);

INSERT INTO comments (product_id, author, body) VALUES
  (1, 'alice', 'Runs cool under the Noctua. No complaints after two months.'),
  (5, 'bob',   'Pulled 360W under load, the 850W PSU is plenty.'),
  (19, 'alice', 'Bought this on a builder''s recommendation, quiet fan curve.');
