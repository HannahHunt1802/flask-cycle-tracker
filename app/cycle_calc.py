from datetime import date, timedelta

#method to fill in info for today-container in dashboard.html
def calculate_cycle_predictions(user):
    settings = getattr(user, "cycle_settings", None)
    logs = getattr(user, "period_log", [])

    #if no data on account
    if not settings or not logs:
        return{"main-event": "No cycle data",
               "main-text": "",
               "secondary-text": ""}

    #retrieve most recent cycle
    latest_log = sorted(logs, key=lambda x: x.period_start or date.min, reverse=True)[0]
    last_start = latest_log.period_start

    if not last_start:
        return {"main-event": "No period recorded",
                "main-text": "",
                "secondary-text": ""}

    today = date.today()
    cycle_length = settings.avg_cycle_length
    period_length = settings.avg_period_length

    #predictions
    next_period = last_start + timedelta(days=cycle_length)
    days_until_period = (next_period - today).days

    ovulation_day = last_start + timedelta(cycle_length // 2)
    days_until_ovulation = (ovulation_day - today).days

    #determine soonest (main) event
    if 0 <= days_until_ovulation <= days_until_period:
        main_text = ""

        # Fertility logic
        if -2 <= days_until_ovulation <= 2:
            main_event = "High fertility today"
        elif days_until_ovulation == 0:
            main_event = "Today"
        elif days_until_ovulation == 1:
            main_event = "1 Day Left"
        else:
            main_event = f"{days_until_ovulation} Days Left"

        secondary_text = f"Next period: {days_until_period} days left"

    else:
        main_event = "Period"

        if days_until_period < 0:
            # currently on period
            main_day_num = abs(days_until_period) + 1
            main_text = f"Day {main_day_num}"
        elif days_until_period == 0:
            main_text = "Today"
        elif days_until_period == 1:
            main_text = "1 Day Left"
        else:
            main_text = f"{days_until_period} Days Left"

        secondary_text = f"Next ovulation: {days_until_ovulation} days left"

    return {
        "main_event": main_event,
        "main_text": main_text,
        "secondary_text": secondary_text}

