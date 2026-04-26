#!/usr/bin/env python3
"""Delete Honda City demo; set overtime_rate_per_hour on each vehicle."""
import requests

API = "https://royal-booking-hub-1.preview.emergentagent.com/api"

# name -> overtime rate (₹/hour)
OVERTIME = {
    "Maruti Fronx (Automatic)": 250,
    "Maruti Fronx": 250,
    "Maruti Baleno": 250,
    "Maruti XL6": 250,
    "Maruti Ertiga": 250,
    "Toyota Innova Crysta": 400,
    "Hyundai i20": 200,
    "Maruti Swift": 200,
    "Hyundai Aura": 200,
    "Hyundai Creta": 350,
    "Mahindra Thar 2x4": 400,
}

def main():
    s = requests.Session()
    s.post(f"{API}/auth/login", json={"email": "admin@royalcars.in", "password": "Admin@12345"}).raise_for_status()
    vehicles = s.get(f"{API}/vehicles", params={"available_only": "false"}).json()
    by_name = {v["name"]: v for v in vehicles}

    # 1. delete Honda City
    hc = by_name.get("Honda City")
    if hc:
        s.delete(f"{API}/vehicles/{hc['id']}").raise_for_status()
        print(f"deleted Honda City")

    # 2. set overtime rates
    for name, rate in OVERTIME.items():
        v = by_name.get(name)
        if not v:
            print(f"skip    {name} (not found)")
            continue
        payload = {k: v.get(k) for k in [
            "name", "type", "fuel_type", "image_urls", "price_per_24hrs",
            "deposit_amount", "is_available", "location_id", "description",
            "seats", "transmission",
        ]}
        payload["overtime_rate_per_hour"] = rate
        r = s.put(f"{API}/vehicles/{v['id']}", json=payload)
        r.raise_for_status()
        print(f"updated {name:<28} overtime ₹{rate}/hr")

if __name__ == "__main__":
    main()
