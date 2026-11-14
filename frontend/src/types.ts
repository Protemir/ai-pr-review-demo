export interface Profile {
  username: string;
  image?: string;
}

export interface Article {
  slug: string;
  title: string;
  description: string;
  createdAt: string;
  author: Profile;
  favoritesCount: number;
}
