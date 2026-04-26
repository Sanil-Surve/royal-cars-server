#!/usr/bin/env python3
"""One-time seed: add 11 vehicles via admin API."""
import requests
import json

API = "https://royal-booking-hub-1.preview.emergentagent.com/api"

# Image URLs chosen per body-style
IMG = {
    "hatchback": "https://images.unsplash.com/photo-1549317661-bd32c8ce0db2?auto=format&fit=crop&w=940&q=80",
    "sedan": "https://images.unsplash.com/photo-1552519507-da3b142c6e3d?auto=format&fit=crop&w=940&q=80",
    "mpv": "https://images.pexels.com/photos/19410427/pexels-photo-19410427.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
    "suv": "https://images.unsplash.com/photo-1758411898312-8592bb81e30d?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDk1Nzd8MHwxfHNlYXJjaHwzfHxwcmVtaXVtJTIwd2hpdGUlMjBzdXYlMjBjYXJ8ZW58MHx8fHwxNzc2NzY1MTM5fDA&ixlib=rb-4.1.0&q=85",
    "premium_suv": "https://images.unsplash.com/photo-1544636331-e26879cd4d9b?auto=format&fit=crop&w=940&q=80",
    "thar": "https://images.unsplash.com/photo-1568844293986-8d0400bd4745?auto=format&fit=crop&w=940&q=80",
}

def deposit_for(price):
    if price <= 2800: return 5000
    if price <= 3000: return 6000
    if price <= 4000: return 8000
    return 10000

VEHICLES = [
    ("Maruti Fronx (Automatic)", "SUV", "Petrol", 2800, "Automatic", 5, "suv", "Compact SUV with automatic transmission and premium interiors."),
    ("Maruti Fronx",             "SUV", "Petrol + CNG", 2500, "Manual", 5, "suv", "Efficient crossover with dual-fuel petrol/CNG option."),
    ("Maruti Ertiga",            "MPV", "Petrol + CNG", 3000, "Manual", 7, "mpv", "7-seater family MPV with petrol/CNG fuel flexibility."),
    ("Maruti XL6",                "MPV", "Petrol + CNG", 3000, "Manual", 6, "mpv", "Premium 6-seater MPV with captain seats."),
    ("Maruti Swift",              "Hatchback", "Petrol + CNG", 2500, "Manual", 5, "hatchback", "Agile city hatchback with CNG economy."),
    ("Hyundai i20",               "Hatchback", "Diesel", 2500, "Manual", 5, "hatchback", "Premium hatchback with strong diesel mileage."),
    ("Maruti Baleno",             "Hatchback", "Petrol + CNG", 2500, "Manual", 5, "hatchback", "Spacious premium hatchback with CNG option."),
    ("Hyundai Aura",              "Sedan", "Petrol + CNG", 2500, "Manual", 5, "sedan", "Compact sedan with boot space and CNG option."),
    ("Toyota Innova Crysta",      "MPV", "Diesel", 5000, "Manual", 7, "mpv", "Premium 7-seater diesel MPV for long trips."),
    ("Hyundai Creta",             "SUV", "Diesel", 4000, "Manual", 5, "premium_suv", "Popular mid-size SUV with punchy diesel engine."),
    ("Mahindra Thar 2x4",         "SUV", "Diesel", 5000, "Manual", 4, "thar", "Iconic off-roader, 2x4 diesel variant."),
]

def main():
    s = requests.Session()
    r = s.post(f"{API}/auth/login", json={"email": "admin@royalcars.in", "password": "Admin@12345"})
    r.raise_for_status()
    print("Admin logged in")

    locs = s.get(f"{API}/locations").json()
    kharghar = next((l for l in locs if "Kharghar" in l["name"]), locs[0])
    panvel = next((l for l in locs if "Panvel" in l["name"]), locs[-1])

    existing_names = {v["name"] for v in s.get(f"{API}/vehicles", params={"available_only": "false"}).json()}

    created, skipped = 0, 0
    for i, (name, vtype, fuel, price, trans, seats, img_key, desc) in enumerate(VEHICLES):
        if name in existing_names:
            print(f"skip  {name} (already exists)")
            skipped += 1
            continue
        body = {
            "name": name,
            "type": vtype,
            "fuel_type": fuel,
            "image_urls": [IMG[img_key]],
            "price_per_24hrs": price,
            "deposit_amount": deposit_for(price),
            "is_available": True,
            "location_id": (kharghar if i % 2 == 0 else panvel)["id"],
            "description": desc,
            "seats": seats,
            "transmission": trans,
        }
        resp = s.post(f"{API}/vehicles", json=body)
        resp.raise_for_status()
        print(f"added {name:<28} {fuel:<14} ₹{price}/day  -> {(kharghar if i%2==0 else panvel)['name']}")
        created += 1

    print(f"\nDone. created={created} skipped={skipped}")

if __name__ == "__main__":
    main()
