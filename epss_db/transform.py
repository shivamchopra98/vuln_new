def transform_epss(data):
    """
    Transform EPSs API data into a clean dict for DynamoDB.
    Each item will have:
        - cve
        - epss
        - percentile
        - date
    """
    transformed = []
    for item in data:
        transformed.append({
            "cve": item["cve"],
            "epss": str(item.get("epss")) if item.get("epss") is not None else None,
            "percentile": str(item.get("percentile")) if item.get("percentile") is not None else None,
            "date": item.get("date")
        })
    return transformed
