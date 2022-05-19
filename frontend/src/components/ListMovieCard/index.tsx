import './styles.css';
import { Movie } from 'types/movie';

type Props = {
  movie: Movie;
};

const ListMovieCard = ({ movie }: Props) => {
  return (
    <div className="list-movie-card">
      <div className="list-movie-card-img-container">
        <img src={movie.imgUrl} alt={movie.title} />
      </div>
      <div className="list-movie-card-data-container">
        <h1 className="list-movie-card-h1_title">{movie.title}</h1>
        <h2 className="list-movie-card-h2_title">{movie.year}</h2>
        <p className="list-movie-card-p_title">{
          movie.subTitle ? movie.subTitle : "  "}</p>
      </div>
    </div>
  );
};

export default ListMovieCard;
