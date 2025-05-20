import pandas as pd

def cleaner():
    df = pd.read_csv("uploaded_file_features.csv")

    # Extract relevant columns
    section_name_cols = [c for c in df.columns if c.startswith("section_") and c.endswith("_name")]
    section_entropy_cols = [c for c in df.columns if c.startswith("section_") and c.endswith("_entropy")]
    section_name_cols.sort()
    section_entropy_cols.sort()

    # Map section name to entropy value
    section_entropy_data = {}
    for idx in range(len(df)):
        row = df.iloc[idx]
        for name_col, entropy_col in zip(section_name_cols, section_entropy_cols):
            section = row[name_col]
            entropy = row[entropy_col]
            if pd.notna(section) and pd.notna(entropy):
                section = section.strip()
                if section not in section_entropy_data:
                    section_entropy_data[section] = [None] * len(df)
                section_entropy_data[section][idx] = entropy

    section_entropy_df = pd.DataFrame(section_entropy_data).fillna(0).astype(float)
    section_entropy_df.index = df.index
    print(f"[STEP 1] Section-entropy DF ➜ rows={section_entropy_df.shape[0]}  cols={section_entropy_df.shape[1]}")

    df['api_calls'] = df['api_calls'].fillna('').astype(str)

    api_data = {}
    for idx, api_list_str in enumerate(df['api_calls']):
        for api in api_list_str.split():
            if api:
                col = f"api_{api}"
                if col not in api_data:
                    api_data[col] = [0] * len(df)
                api_data[col][idx] = 1

    api_df = pd.DataFrame(api_data)
    api_df.index = df.index
    print(f"[STEP 2] API-calls DF     ➜ rows={api_df.shape[0]}  cols={api_df.shape[1]}")

    df['api_calls'] = df['api_calls'].fillna('').astype(str)

    api_data = {}
    for idx, api_list_str in enumerate(df['api_calls']):
        for api in api_list_str.split():
            if api:
                col = f"api_{api}"
                if col not in api_data:
                    api_data[col] = [0] * len(df)
                api_data[col][idx] = 1

    api_df = pd.DataFrame(api_data)
    api_df.index = df.index
    print(f"[STEP 2] API-calls DF     ➜ rows={api_df.shape[0]}  cols={api_df.shape[1]}")

    df_core = df.drop(columns=section_name_cols + section_entropy_cols + ['api_calls'])
    df_cleaned = pd.concat([df_core, section_entropy_df, api_df], axis=1)

    df_cleaned.to_csv("pipe1.csv", index=False)
    print(f"[OUTPUT] pipe1.csv        ➜ rows={df_cleaned.shape[0]}  cols={df_cleaned.shape[1]}")

    df = pd.read_csv("pipe1.csv")
    api_cols = [col for col in df.columns if col.startswith('api_')]
    dropped_cols = [col for col in api_cols if df[col].sum() <= 2]
    df.drop(columns=dropped_cols, inplace=True)

    df.to_csv("pipe2.csv", index=False)
    print(f"[OUTPUT] pipe2.csv ➜ rows={df.shape[0]}  cols={df.shape[1]}")

    def drop_rare_entropy_columns_by_index_nonzero(df, start_idx=260, end_idx=267, threshold=2):
        cols_to_check = df.columns[start_idx:end_idx + 1]
        cols_to_drop = [col for col in cols_to_check if (df[col] > 0).sum() <= threshold]

        if cols_to_drop:
            df.drop(columns=cols_to_drop, inplace=True)
            print(f"Dropped {len(cols_to_drop)} columns with ≤ {threshold} non-zero entries:")
            print(cols_to_drop)
        else:
            print("No columns dropped.")

        return df

    df = pd.read_csv('pipe2.csv')
    df = drop_rare_entropy_columns_by_index_nonzero(df)
    df.to_csv('output.csv', index=False)
    print("Successfully saved → output.csv")
