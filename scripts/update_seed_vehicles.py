#!/usr/bin/env python3
"""Update the 3 pre-seeded demo vehicles to match user-specified pricing/fuel."""
import requests

API = "https://royal-booking-hub-1.preview.emergentagent.com/api"
IMG_HATCH = "https://images.unsplash.com/photo-1549317661-bd32c8ce0db2?auto=format&fit=crop&w=940&q=80"
IMG_MPV = "https://images.pexels.com/photos/19410427/pexels-photo-19410427.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940"
IMG_SUV = "https://images.unsplash.com/photo-1544636331-e26879cd4d9b?auto=format&fit=crop&w=940&q=80"

UPDATES = {
    "Maruti Swift": {
        "name": "Maruti Swift", "type": "Hatchback", "fuel_type": "Petrol + CNG",
        "image_urls": [IMG_HATCH], "price_per_24hrs": 2500, "deposit_amount": 5000,
        "is_available": True, "description": "Agile city hatchback with CNG economy.",
        "seats": 5, "transmission": "Manual",
    },
    "Toyota Innova Crysta": {
        "name": "Toyota Innova Crysta", "type": "MPV", "fuel_type": "Diesel",
        "image_urls": [IMG_MPV], "price_per_24hrs": 5000, "deposit_amount": 10000,
        "is_available": True, "description": "Premium 7-seater diesel MPV for long trips.",
        "seats": 7, "transmission": "Manual",
    },
    "Hyundai Creta": {
        "name": "Hyundai Creta", "type": "SUV", "fuel_type": "Diesel",
        "image_urls": [IMG_SUV], "price_per_24hrs": 4000, "deposit_amount": 8000,
        "is_available": True, "description": "Popular mid-size SUV with punchy diesel engine.",
        "seats": 5, "transmission": "Manual",
    },
}

def main():
    s = requests.Session()
    s.post(f"{API}/auth/login", json={"email": "admin@royalcars.in", "password": "Admin@12345"}).raise_for_status()
    vehicles = s.get(f"{API}/vehicles", params={"available_only": "false"}).json()
    by_name = {v["name"]: v for v in vehicles}
    for name, payload in UPDATES.items():
        v = by_name.get(name)
        if not v:
            print(f"skip  {name} (not found)")
            continue
        payload["location_id"] = v.get("location_id")
        r = s.put(f"{API}/vehicles/{v['id']}", json=payload)
        r.raise_for_status()
        print(f"updated {name:<24} {payload['fuel_type']:<14} ₹{payload['price_per_24hrs']}/day")

if __name__ == "__main__":
    main()
