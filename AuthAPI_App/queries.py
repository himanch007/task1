
def get_terms_query(list_of_ids):
    return {
        "query": {
            "terms": {
                "id": list_of_ids
            }
        }
    }
    